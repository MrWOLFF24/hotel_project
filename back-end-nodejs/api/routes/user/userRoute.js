'use strict';
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const moment = require('moment');
const fs = require('fs');

// import user model and auth middleware
const auth = require('./../../middleware/auth');
const upload = require('./../../middleware/uploader');
const checkAuth = require('./../../middleware/check-auth');
const userModel = require('./../../models/userModel');

// post a new user
router.post('/register', (req, res) => {
  try {
    userModel.register(response => {
    res.status(201).send(response);
    }, req.body);
  } catch(err) {
    res.boom.badImplementation('soucis durant la création du user');
  }
});

// authenticate use with credentials and respond with signed jwt token
router.post('/authenticate', (req, res) => {
  if (!req.body) {
    return res.boom.badImplementation('access non autorisé au serveur');
  }

  userModel.authenticate(response => {
      if (!response.error) {
        const payload = { user: response.user, message: response.message };
        const token = jwt.sign(payload, process.env.PRIVATE_KEY.replace(/\\n/g, '\n'), { expiresIn: '2 days', algorithm: 'RS256' }); // expires in 24 hours
        response.token = token;
        response.expires = moment(moment().add(2, 'd')).format("x");
        return res.status(201).send(response);
      } else {
        res.boom.unauthorized(response);
      }
  }, req.body); // le second param de userModel.login() est ici !!!
});

router.patch('/avatar', checkAuth, upload.single('avatar'), (req, res, next) => {
  if (req.body.url) {
    fs.unlinkSync(req.body.url);
  }
  userModel.patch.avatar(response => {
    res.status(201).send(response);
  }, req.file.path, req.userData.user.id);
});

router.patch('/password', checkAuth, (req, res, next) => {
  if (req.userData.user.is_admin) {
    userModel.patch.password(response => {
      res.status(201).send(response);
    }, req.body);
  } else {
    res.status(403).send({message: 'Vous n\'êtes pas autorisé à effectuer cette action.'});
  }
});

router.delete('/:id', checkAuth, (req, res) => {
  if (req.userData.user.is_admin) {
    userModel.remove((response) => {
        res.status(201).send(response);
    }, req.params.id);
  } else {
    res.status(403).send({message: 'Vous n\'êtes pas autorisé à effectuer cette action.'});
  }
});

router.put('/', checkAuth, (req, res) => {
  if (req.userData.user.is_admin) {
    userModel.putUser((response) => {
      res.status(201).send(response);
    }, req.body);
  } else {
    res.status(403).send({message: 'Vous n\'êtes pas autorisé à effectuer cette action.'});
  }
});

router.get('/', checkAuth, (req, res) => {
  if (req.userData.user.is_admin) {
    userModel.getUser((response) => {
      res.status(201).send(response);
    });
  } else {
    res.status(403).send({message: 'Vous n\'êtes pas autorisé à effectuer cette action.'});
  }
});

router.post('/getAvatar', checkAuth, (req, res) => {
  if (req.body.avatar) {
    setTimeout(() => {
      const ext = req.body.avatar.split('.');
      const binaryImage = fs.readFileSync(req.body.avatar);
      const newImage = {
        contentType: `image/${ext[1]}`,
        data: binaryImage
      };
      res.status(201).send(newImage);
    }, 500);
  }
});

router.get('/getById', checkAuth, (req, res) => {
  userModel.getUser((response) => {
    res.status(201).send(response);
  }, req.userData.user.id);
});

module.exports = router;
