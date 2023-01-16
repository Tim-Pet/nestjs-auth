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
import { SignUpDto } from './dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigType } from '@nestjs/config';
import jwtConfig from '../config/jwt.config';
import { ActiveUserData } from '../interface/active-user-data.interface';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { RefreshTokenIdsStorage } from './refresh-token-ids.storage/refresh-token-ids.storage';
import { randomUUID } from 'crypto';

@Injectable()
export class AuthenticationService {
  constructor(
    @InjectRepository(User) private readonly usersRepository: Repository<User>,
    private readonly hashingService: HashingService,
    private readonly jwtService: JwtService,
    // Grab the config key-value pairs
    @Inject(jwtConfig.KEY)
    private readonly jwtConfiguration: ConfigType<typeof jwtConfig>,
    private readonly refreshTokenIdsStorage: RefreshTokenIdsStorage,
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

    return await this.generateTokens(user);
  }

  async refreshTokens(refreshTokenDto: RefreshTokenDto) {
    try {
      const { sub, refreshTokenId } = await this.jwtService.verifyAsync<
        Pick<ActiveUserData, 'sub'> & { refreshTokenId: string }
      >(refreshTokenDto.refreshToken, {
        secret: this.jwtConfiguration.secret,
        issuer: this.jwtConfiguration.issuer,
        audience: this.jwtConfiguration.audience,
      });

      const user = await this.usersRepository.findOneByOrFail({ id: sub });

      const isValid = await this.refreshTokenIdsStorage.validate(
        user.id,
        refreshTokenId,
      );

      if (isValid) {
        await this.refreshTokenIdsStorage.invalidate(user.id);
      } else {
        throw new Error('Refresh token is not valid');
      }
      return await this.generateTokens(user);
    } catch (err) {
      if (err instanceof UnauthorizedException) {
        // take action if the error is UnauthorizedException that the users refreshToken might have been exposed/stolen
        throw new UnauthorizedException('Access denied');
      }
      throw new UnauthorizedException();
    }
  }

  async generateTokens(user: User) {
    const refreshTokenId = randomUUID();
    try {
      const [accessToken, refreshToken] = await Promise.all([
        this.signToken<Partial<ActiveUserData>>(
          user.id,
          this.jwtConfiguration.accessTokenTtl,
          {
            email: user.email,
          },
        ),
        this.signToken(user.id, this.jwtConfiguration.refreshTokenTtl, {
          refreshTokenId,
        }),
      ]);
      await this.refreshTokenIdsStorage.insert(user.id, refreshTokenId);
      return {
        accessToken,
        refreshToken,
      };
    } catch {
      throw new UnauthorizedException();
    }
  }

  private async signToken<T>(userId: number, expiresIn: number, payload?: T) {
    return await this.jwtService.signAsync(
      {
        sub: userId,
        ...payload,
      },
      {
        audience: this.jwtConfiguration.audience,
        issuer: this.jwtConfiguration.issuer,
        secret: this.jwtConfiguration.secret,
        expiresIn: this.jwtConfiguration.accessTokenTtl,
      },
    );
  }
}
