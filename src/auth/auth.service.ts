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
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private UserModel: Model<User>,
    private jwtService: JwtService,
    private mailerService: MailerService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    // @Inject(CACHE_MANAGER) private cacheManager: Cache,
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

  async login(User: SignUpDto): Promise<{ ticket: string }> {
    const { email, password } = User;
    const user = await this.UserModel.findOne({ email });
    if (!user) {
      throw new BadRequestException('Email not exist');
    }

    if (!(await bcrypt.compare(password, user.password))) {
      throw new BadRequestException('Password incorrect');
    }

    const payload = { email: user.email, id: user._id };
    const token = this.jwtService.sign(payload);

    const ticket = generateTicket(user);
    await this.cacheManager.set('ticket', ticket, {
      ttl: process.env.TICKET_EXPIRE,
    });

    // const value = await this.cacheManager.get('ticket');
    // console.log('value', value);

    console.log('ticket', ticket);
    // await this.mailerService.sendMail({
    //   from: process.env.MAIL_USER,
    //   to: email,
    //   subject: 'demo email',
    //   template: './confirmation',
    //   context: {
    //     // ✏️ filling curly brackets with content
    //     name: user.name,
    //     url: `example.com/auth/confirm?token=${ticket}`,
    //   },
    // });
    return {
      ticket: ticket,
    };
  }
  async resendEmail(user, ticket: string): Promise<{ new_ticket: string }> {
    const old_ticket = await this.cacheManager.get('ticket');
    console.log('old', old_ticket);
    console.log('ticket', ticket);
    if (old_ticket != ticket) throw new BadRequestException('invalid ticket');
    const new_ticket = generateTicket(user);

    await this.mailerService.sendMail({
      from: process.env.MAIL_USER,
      to: user.email,
      subject: 'Resend email',
      template: './confirmation',
      context: {
        name: user.name,
        url: `example.com/auth/confirm?token=${ticket}`,
      },
    });
    return { new_ticket: new_ticket };
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

export function decodeToken(token: string): any {
  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET,
    );
    return decoded;
  } catch (err) {
    console.error(err);
    throw new Error('Invalid token');
  }
}
