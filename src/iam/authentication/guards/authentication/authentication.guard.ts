import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { AUTH_TYPE_KEY } from '../../decorators/auth.decorator';
import { AuthType } from '../../enums/auth-type.enum';
import { AccessTokenGuard } from '../access-token/access-token.guard';

@Injectable()
export class AuthenticationGuard implements CanActivate {
  private static readonly defaultAuthType = AuthType.Bearer;
  private readonly authTypeGuardMap: Record<
    AuthType,
    CanActivate | CanActivate[]
  > = {
    [AuthType.Bearer]: [this.accessTokenGuard],
    [AuthType.None]: { canActivate: () => true },
  };
  constructor(
    private readonly reflector: Reflector, // Reflector is used to get the metadata of the controller or method
    private readonly accessTokenGuard: AccessTokenGuard, // AccessTokenGuard is used to verify the access token
  ) {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const authTypes = this.reflector.getAllAndOverride<AuthType[]>(
      AUTH_TYPE_KEY,
      [context.getHandler(), context.getClass()],
    ) ?? [AuthenticationGuard.defaultAuthType];

    const guards = authTypes.map((type) => this.authTypeGuardMap[type]).flat();

    let error = new UnauthorizedException();

    const isGuarded = guards.some(async (guard) => {
      const canActivate = await Promise.resolve(
        guard.canActivate(context),
      ).catch((err) => (error = err));
      if (canActivate) {
        return true;
      }
    });

    if (isGuarded) {
      return true;
    }
    throw error;
  }
}
