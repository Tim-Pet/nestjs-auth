import {
  ConflictException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';
import { HashingService } from '../hashing/hashing.service';
import { SignUpDto } from './dto/sign-up.dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto/sign-in.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigType } from '@nestjs/config';
import jwtConfig from '../config/jwt.config';

@Injectable()
export class AuthenticationService {
  constructor(
    @InjectRepository(User) private readonly usersRepository: Repository<User>,
    private readonly hashingService: HashingService,
    private readonly jwtService: JwtService,
    // Grab the config key-value pairs
    @Inject(jwtConfig.KEY)
    private readonly jwtConfiguration: ConfigType<typeof jwtConfig>,
  ) {}

  async signUp(SignUpDto: SignUpDto) {
    try {
      const user = new User();
      user.email = SignUpDto.email;
      user.password = await this.hashingService.hash(SignUpDto.password);

      await this.usersRepository.save(user);
    } catch (err) {
      const pgUniqueViolationErrorCode = '23505';
      if (err.code === pgUniqueViolationErrorCode) {
        throw new ConflictException();
      }
      throw err;
    }
  }

  async signIn(SignInDto: SignInDto) {
    // get user and check wether the user exist
    const user = await this.usersRepository.findOneBy({
      email: SignInDto.email,
    });
    if (!user) {
      return new UnauthorizedException('User does not exist');
    }

    // compare passwords
    const isEqual = await this.hashingService.compare(
      SignInDto.password,
      user.password,
    );
    if (!isEqual) {
      throw new UnauthorizedException('Password does not match');
    }

    const accessToken = await this.jwtService.signAsync(
      {
        sub: user.id, // for whom is the claim
        email: user.email,
      },
      {
        audience: this.jwtConfiguration.audience, // the recipients that the JWT is intended for
        issuer: this.jwtConfiguration.issuer, // the principal that issued the JWT
        secret: this.jwtConfiguration.secret,
        expiresIn: this.jwtConfiguration.accessTokenTtl, // the expiration time on or after which the JWT MUST NOT be accepted for processing
      },
    );

    return accessToken;
  }
}
