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
    AuthenticationService,
  ],
  controllers: [AuthenticationController],
})
export class IamModule {}
