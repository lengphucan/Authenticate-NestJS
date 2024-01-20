import {
  Body,
  Controller,
  Post,
  Req,
  UnauthorizedException,
  UseInterceptors,
} from '@nestjs/common';
import { AuthService, decodeToken } from './auth.service';
import { SignUpDto } from './dto/signup.dto';
import { CacheInterceptor } from '@nestjs/cache-manager';
import { ResendEmailDto } from './dto/resend.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  async signUp(
    @Body() user: SignUpDto,
  ): Promise<{ message: string; data: { username: string; email: string }[] }> {
    return this.authService.signUp(user);
  }

  @Post('login')
  async login(@Body() user: SignUpDto): Promise<{ ticket: string }> {
    return this.authService.login(user);
  }

  @Post('resend-email')
  async resendEmail(
    @Req() request: Request,
    @Body() data: ResendEmailDto,
  ): Promise<{ new_ticket: string }> {
    const token = request.headers['authorization'];
    if (!token) {
      throw new UnauthorizedException('Authorization header is missing');
    }
    const user = decodeToken(token);

    return this.authService.resendEmail(user, data.ticket);
  }

  @Post('logout')
  async logout(@Req() request): Promise<{ message: string }> {
    return this.authService.logout(request.headers.authorization);
  }
}
