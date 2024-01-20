import { IsNotEmpty } from 'class-validator';

export class ResendEmailDto {
  @IsNotEmpty()
  readonly ticket: string;
}
