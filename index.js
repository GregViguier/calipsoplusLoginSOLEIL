const express = require('express');
const ldap = require('ldapjs');
const { promisify } = require('util');

// Express
const app = express();
const port = 7000;
app.use(express.json()); // for parsing application/json

// LDAP
const rootDN = 'OU=Users,DC=exp,DC=synchrotron-soleil,DC=fr';
const baseDN = 'CN=service_jra2,OU=services,OU=Users,DC=exp,DC=synchrotron-soleil,DC=fr';
const jra2LdapSecret = 'S3rv1c3JR42#?';

// Winston
const { format, createLogger, transports } = require('winston');

const logger = createLogger({
  format: format.combine(
    format.timestamp({
      format: 'YYYY-MM-DD HH:mm:ss',
    }),
    format.simple(),
  ),
  transports: [
    new transports.File({ filename: 'error.log', level: 'error' }),
    new transports.File({ filename: 'combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(
    new transports.Console({
      format: format.simple(),
    }),
  );
}

function error(status, msg) {
  const err = new Error(msg);
  err.status = status;
  return err;
}

const validateInput = function validateUsernameAndPassword(req, res, next) {
  const { username } = req.body;
  const { password } = req.body;

  if (username === undefined || password === undefined) {
    const errorMsg = "Expected 'username' and 'password'";
    logger.error(errorMsg);
    next(error(400, errorMsg));
  } else {
    next();
  }
};

app.post('/login', validateInput, async (req, res, next) => {
  const { username } = req.body;
  const { password } = req.body;

  const status = 200;
  const message = 'OK';

  const client = ldap.createClient({
    url: 'ldap://localhost:1389',
  });

  const bindAsync = promisify(client.bind).bind(client);

  try {
    await bindAsync(baseDN, jra2LdapSecret);
  } catch (err) {
    logger.error(err);
    return next(error(400, 'Cannot bind LDAP with JRA2 service account'));
  }

  const opts = {
    filter: `cn=${username}`,
    scope: 'sub',
    attributes: ['dn'],
  };

  await client.search(rootDN, opts, (_, searchRes) => {
    searchRes.once('searchEntry', async (entry) => {
      const { dn } = entry.object;
      try {
        await bindAsync(dn, password);
      } catch (err) {
        logger.error(`User ${dn} not authorized (incorrect password)`);
        return next(error(401, 'Unauthorized'));
      }
      client.unbind();
      return res.status(status).send(message);
    });
  });
  return 1;
});

// Custom Express Error Handler
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  res.status(err.status || 500);
  res.send({ error: err.message });
});

app.listen(port, () => logger.info(`Example app listening on port ${port}!`));
