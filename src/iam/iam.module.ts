import { Module } from '@nestjs/common';
import { HashingService } from './hashing/hashing.service';
import { BcryptService } from './hashing/bcrypt.service';
import { AuthenticationController } from './authentication/authentication.controller';
import { AuthenticationService } from './authentication/authentication.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { JwtModule } from '@nestjs/jwt';
import jwtConfig from './config/jwt.config';
import { ConfigModule } from '@nestjs/config';
import { AccessTokenGuard } from './authentication/guards/access-token/access-token.guard';
import { APP_GUARD } from '@nestjs/core';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]), // make user available
    JwtModule.registerAsync(jwtConfig.asProvider()), // register jwt namespace
    ConfigModule.forFeature(jwtConfig), // register jwt config to grant access to envs
  ],
  providers: [
    {
      provide: HashingService, // Service declaration
      useClass: BcryptService, // Service implementation
    },
    {
      provide: APP_GUARD,
      useClass: AccessTokenGuard,
    },
    AuthenticationService,
  ],
  controllers: [AuthenticationController],
})
export class IamModule {}
