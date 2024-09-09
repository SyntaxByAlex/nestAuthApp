import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import * as request from 'supertest';
import { JwtPayload } from '../interfaces/jwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(
    private readonly jwtService: JwtService,
    private readonly authService: AuthService
  ) { }
  async canActivate(context: ExecutionContext): Promise<boolean> {

    const request = context.switchToHttp().getRequest();
    const token = request.headers.authorization?.replace('Bearer ', '');

    if (!token) {
      throw new UnauthorizedException();
    }

    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(token, {
        secret: process.env.JWT_SECRET
      });

      const user = await this.authService.findUserById(payload.id);

      if(!user) {
        throw new UnauthorizedException("User not found");
      }

      if(!user.isActive) {
        throw new UnauthorizedException("User is not active");
      }

      request['user'] = user;

    } catch (error) {
      throw new UnauthorizedException();
    }
    return true;
  }
}
