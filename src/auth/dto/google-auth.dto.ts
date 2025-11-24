import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class GoogleDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  googleId: string
}
