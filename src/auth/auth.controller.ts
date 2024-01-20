import { Body, Controller, Post, Req, UseInterceptors } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from './dto/signup.dto';
import { CacheInterceptor } from '@nestjs/cache-manager';

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
  async login(@Body() user: SignUpDto): Promise<{ token: string }> {
    return this.authService.login(user);
  }

  @Post('resendEmail')
  async resendEmail(@Req() request): Promise<{ message: string }> {
    return this.authService.resendEmail(request.headers.authorization);
  }
  @Post('logout')
  async logout(@Req() request): Promise<{ message: string }> {
    return this.authService.logout(request.headers.authorization);
  }
}
