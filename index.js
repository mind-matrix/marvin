const express = require('express');
const compression = require('compression');
const bodyParser = require('body-parser');
const FastMap = require('collections/fast-map');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { Service, User } = require('./model');
const { readFileSync } = require('fs');
const WebSocket = require('ws');
const uniqid = require('uniqid');

const cors = require('cors');

const { SERVICE } = require('./constants.js');

const privateKey = readFileSync('private.key');
const publicKey = readFileSync('public.key');

const services = new FastMap();

function getBytes(string){
  return Buffer.byteLength(string, 'utf8')
}

mongoose.connect('mongodb+srv://marvin:JyZtmjwpslIwf8vn@cluster0-84baf.mongodb.net/test?retryWrites=true&w=majority', {useNewUrlParser: true}).then(() => {
  const api = express();

  api.use(cors());

  api.use(compression());

  api.use(bodyParser.json());

  api.post('/login', async function (req, res) {
    if(req.body.username && req.body.password) {
      var user = await User.findOne({ username: req.body.username }).select('+password');
      if(user.validatePassword(req.body.password)) {
        var token = jwt.sign({
          username: user.username
        }, privateKey, { algorithm: 'RS256' });
        res.status(200).send({
          token,
          error: null
        });
      } else {
        res.status(403).send({
          error: `Invalid Username or Password`
        });
      }
    } else {
      res.status(403).send({
        error: `A valid Username or Password has not been provided`
      });
    }
  });

  api.post('/register', async function (req, res) {
    if(req.body.name && req.body.username && req.body.email && req.body.password) {
      if(await User.isAvailable({ username: req.body.username, email: req.body.email })) {
        var user = new User({
          name: req.body.name,
          email: req.body.email,
          username: req.body.username
        });
        user.setPassword(req.body.password);
        var token = jwt.sign({
          username: user.username
        }, privateKey, { algorithm: 'RS256' });
        await user.save();
        res.status(200).send({
          token,
          error: null
        });
      } else {
        res.status(403).send({
          error: `Username or Email already in use`
        });
      }
    } else {
      res.status(403).send({
        error: `Invalid or incomplete request`
      });
    }
  });

  const apiAuthMiddleware = async function (req, res, next) {
    try {
      if(req.headers.authorization) {
        const token = req.headers.authorization;
        const decodedToken = jwt.verify(token, publicKey);
        const username = decodedToken.username;
        const user = await User.findOne({ username });
        if (user) {
          req.context = { user };
        } else {
          req.context = {};
        }
      } else {
        req.context = {};
      }
      next();
    } catch {
      res.status(403).json({
        error: new Error('Invalid request!')
      });
    }
  };

  api.get('/me', apiAuthMiddleware, async function (req, res) {
    if(req.context.user) {
      res.status(200).send(await req.context.user);
    }
  });

  api.get('/validate/:entity/:field', apiAuthMiddleware, async function (req, res) {
    if(req.params.entity === 'user') {
      if(req.params.field === 'username') {
        res.status(200).send({
          available: await User.isAvailable({ username: req.query.q })
        });
      }
    } else if(req.params.entity === 'service') {
      if(req.params.field === 'identifier') {
        if(req.context.user) {
          res.status(200).send({
            available: await Service.isAvailable(req.query.q)
          });
        } else {
          res.status(403).send({
            error: `Unauthorized access`
          });
        }
      }
    } else {
      res.status(403).send({
        error: `Query on invalid entity`
      });
    }
  });

  api.post('/services/:action', apiAuthMiddleware, async function (req, res) {
    if(req.context.user) {
      var action = req.params.action;
      if(action === 'add') {
        var { identifier, name, meta, testing, procedures, scope } = req.body;
        if(await Service.isAvailable(identifier)) {
          var service = new Service({
            identifier,
            name,
            meta,
            testing,
            procedures,
            scope
          });
          service.generateAPIKey();
          await service.save();
          req.context.user.services.addToSet(service._id);
          await req.context.user.save();
          res.status(200).send({
            token: jwt.sign({
              serviceId: service.identifier
            }, privateKey, { algorithm: 'RS256' }),
            error: null
          });
        } else {
          res.status(403).send({
            error: `Identifier already in use`
          });
        }
      } else if(action === 'update') {
        var { identifier, set } = req.body;
        delete set.apiKeys;
        var service = await Service.updateOne({ identifier }, set);
        res.status(200).send({
          error: null
        });
      } else if(action === 'generate-token') {
        var { identifier } = req.body;
        var service = await Service.findOne({ identifier });
        if(req.context.user.services.includes(service._id)) {
          res.status(200).send({
            token: jwt.sign({
              serviceId: service.identifier
            }, privateKey, { algorithm: 'RS256' }),
            error: null
          });
        } else {
          res.status(403).send({
            error: `Invalid Service ID`
          });
        }
      } else if(action === 'remove-key') {
        var { identifier, key } = req.body;
        var service = await Service.findOne({ identifier });
        if(req.context.user.services.includes(service._id)) {
          service.apiKeys.pull(key);
          await service.save();
          res.status(200).send({
            error: null
          });
        } else {
          res.status(403).send({
            error: `Invalid Service ID`
          });
        }
      } else if(action === 'generate-key') {
        var { identifier } = req.body;
        var service = await Service.findOne({ identifier });
        if(req.context.user.services.includes(service._id)) {
          var key = service.generateAPIKey();
          await service.save();
          res.status(200).send({
            key: key,
            error: null
          });
        } else {
          res.status(403).send({
            error: `Invalid Service ID`
          });
        }
      } else if(action === 'get') {
        res.send({
          services: (await User.populate(req.context.user, 'services')).services,
          error: null
        });
      } else if(action === 'remove') {
        await Service.findOneAndRemove({ identifier: req.body.identifier });
        res.send({
          deleted: true,
          error: null
        });
      }
    } else {
      res.status(403).send({
        error: `Unauthorized access`
      });
    }
  });

  const wss = new WebSocket.Server({ server: api });
  
  wss.on('connection', (ws) => {
    ws.on('message', async function (message) {
      var req = JSON.parse(message);
      let service;
      if(req.token) {
        const decodedToken = jwt.verify(req.token, publicKey);
        const serviceId = decodedToken.serviceId;
        service = await Service.findOne({ identifier: serviceId });
        if(service)
          req.context = { service };
        else
          req.context = {};
      } else {
        req.context = {};
      }

      if(req.context.service) {
        if(req.data) {
          if(req.data.action === 'activate') {
            if(service.usage <= SERVICE.LIMIT.USAGE.FREE)
              service.status = SERVICE.STATUS.AVAILABLE;
            else
              service.status = SERVICE.STATUS.QUOTA_EXPIRED;
            services.set(service.identifier, {
              connection: ws,
              listeners: new Map()
            });
            ws.id = service.identifier;
          } else if(ws.id) {
            if (req.data.action === 'deactivate') {
              service.status = SERVICE.STATUS.UNAVAILABLE;
              if(services.has(ws.id))
                services.delete(ws.id);
              ws.id = undefined;
            }
            else if(req.data.action === 'update-procedures' && req.data.procedures) {
              service.procedures = req.data.procedures;
            } else if(req.data.action === 'message' && req.data.clientId) {
              if(req.data.message.response === 'answer') {
                req.data.message.procedures = service.procedures;
              }
              var activeServiceInstance = services.get(service.identifier);
              var listener = activeServiceInstance.listeners.get(req.data.clientId);
              listener.send(
                JSON.stringify({
                  serviceId: service.identifier,
                  message: req.data.message
                })
              );
              service.usage += getBytes(JSON.stringify(req.data.message));
            }
          }
          service.save();
        }
      } else {
        if(req.data && req.serviceId) {
          service = await Service.findOne({ identifier: req.serviceId });
          if(service.scope === SERVICE.SCOPE.PUBLIC) {
            var clientId = uniqid(service.identifier);
            var activeServiceInstance = services.get(service.identifier);
            activeServiceInstance.listeners.set(clientId, ws);
            activeServiceInstance.connection.send(
              JSON.stringify({
                clientId,
                message: req.data.message
              })
            );
            service.usage += getBytes(JSON.stringify(req.data.message));
            service.save();
          } else if(
            service.scope === SERVICE.SCOPE.PRIVATE && 
            req.data.key && 
            service.apiKeys.includes(req.data.key)
          ) {
            if(service.usage > SERVICE.LIMIT.USAGE.FREE) {
              ws.send(
                JSON.stringify({
                  error: `CAP LIMIT EXCEEDED`
                })
              );
            } else if(!services.has(service.identifier)) {
              ws.send(
                JSON.stringify({
                  error: `Service not available`
                })
              );
            } else {
              var clientId = uniqid(service.identifier);
              ws.clientId = clientId;
              ws.serviceId = service.identifier;
              var activeServiceInstance = services.get(service.identifier);
              activeServiceInstance.listeners.set(clientId, ws);
              activeServiceInstance.connection.send(
                JSON.stringify({
                  clientId,
                  message: req.data.message
                })
              );
              service.usage += getBytes(JSON.stringify(req.data.message));
              service.save();
            }
          }
        }
      }
    });
    ws.on('close', async function () {
      if(ws.id && services.has(ws.id)) {
        let service = await Service.findOne({ identifier: ws.id });
        service.status = SERVICE.STATUS.UNAVAILABLE;
        services.delete(ws.id);
        ws.id = undefined;
      }
      if(ws.clientId && ws.serviceId) {
        services.get(ws.serviceId).listeners.delete(ws.clientId);
        ws.clientId = undefined;
        ws.serviceId = undefined;
      }
    });
  });

  api.listen(80, () => {
    console.log(`API Server running at port 80`);
  });
});