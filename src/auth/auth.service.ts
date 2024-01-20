import {
  BadRequestException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { SignUpDto } from './dto/signup.dto';
import { MailerService } from '@nestjs-modules/mailer';
import { CACHE_MANAGER, Cache } from 'cache-manager';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private UserModel: Model<User>,
    private jwtService: JwtService,
    private mailerService: MailerService,
    @Inject(CACHE_MANAGER) private cacheManage: Cache,
  ) {}

  async signUp(
    User: SignUpDto,
  ): Promise<{ message: string; data: { username: string; email: string }[] }> {
    const { name, email, password } = User;

    const existingUser = await this.UserModel.findOne({ email });
    if (existingUser) {
      throw new BadRequestException('Email already in use.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await this.UserModel.create({
      name,
      email,
      password: hashedPassword,
    });

    return {
      message: 'Register successful',
      data: [
        {
          username: user.name,
          email: user.email,
        },
      ],
    };
  }

  async login(User: SignUpDto): Promise<{ token: string }> {
    const { email, password } = User;
    const user = await this.UserModel.findOne({ email });
    if (!user) {
      throw new BadRequestException('Email not exist');
    }

    if (!(await bcrypt.compare(password, user.password))) {
      throw new BadRequestException('Password incorrect');
    }

    const payload = { email: user.email, sub: user._id };
    const token = this.jwtService.sign(payload);

    const ticket = generateTicket(user);

    console.log(ticket);
    // await this.mailerService.sendMail({
    //   from: 'anlenguyen0110@gmail.com',
    //   to: email,
    //   subject: 'demo email',
    //   template: './confirmation',
    //   context: {
    //     // ✏️ filling curly brackets with content
    //     name: user.name,
    //     url: `example.com/auth/confirm?token=${token}`,
    //   },
    // });
    return {
      token: token,
    };
  }
  async resendEmail(ticket: string): Promise<{ message: string }> {
    return { message: '' };
  }

  async logout(token: string): Promise<{ message: string }> {
    const decoded = this.jwtService.decode(token);
    if (!decoded) {
      throw new UnauthorizedException('Invalid token');
    }

    return { message: 'logout successful' };
  }
}

function encodeBase64AndStrip(data) {
  // Encode data using base64 and remove trailing '=' characters
  let encoded = Buffer.from(String(data), 'ascii').toString('base64');
  return encoded.replace(/=+$/, '');
}

function generateTicket(user) {
  let userId = encodeBase64AndStrip(user.id);
  let time = encodeBase64AndStrip(Math.floor(Date.now() / 1000));
  let randomStr = getRandomString(16);

  return `${randomStr}.${userId}.${time}`;
}

function getRandomString(length) {
  // Generating a random string of specified length
  let result = '';
  let characters =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let charactersLength = characters.length;
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}
