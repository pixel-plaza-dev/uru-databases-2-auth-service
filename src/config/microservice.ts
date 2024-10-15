// User Microservice configuration
export const IS_PRODUCTION = process.env.NODE_ENV === 'production';
export const AUTH_MICROSERVICE_PORT = parseInt(
    process.env.AUTH_MICROSERVICE_PORT
);

