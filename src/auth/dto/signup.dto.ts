import {
  IsEmail,
  IsEnum,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
  MinLength,
} from 'class-validator';

export class SignUpDto {
  @IsOptional()
  @IsString()
  readonly name: string;

  @IsOptional()
  @IsEmail({}, { message: 'please enter correct email' })
  readonly email: string;

  @IsOptional()
  @IsString()
  @MinLength(6)
  readonly password: string;
}
