import {NestFactory} from '@nestjs/core';
import {AppModule} from './app.module';
import {MicroserviceOptions, Transport} from "@nestjs/microservices";
import {AUTH_MICROSERVICE_PORT} from "./config/microservice";

async function bootstrap() {
    const app = await NestFactory.createMicroservice<MicroserviceOptions>(AppModule, {
        transport: Transport.TCP,
        options: {
            port: AUTH_MICROSERVICE_PORT,
        },
    });
    await app.listen();
}

bootstrap();
