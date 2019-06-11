require('dotenv').config();

const normalizePort = require('normalize-port');
const { app, logger } = require('./app');

/**
 * Get port from environment and store in Express.
 */

const port = normalizePort(process.env.PORT || '3000');

app.listen(port, () => logger.info(`Example app listening on port ${port}!`));
