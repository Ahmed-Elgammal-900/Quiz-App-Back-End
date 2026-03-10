import {
  IsEmail,
  IsString,
  MinLength,
  MaxLength,
  Matches,
  IsNotEmpty,
} from 'class-validator';
import { MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH } from '../constants/auth.constants';

export class CreateAuthDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(MIN_PASSWORD_LENGTH, { message: 'Password must be at least 8 characters long' })
  @MaxLength(MAX_PASSWORD_LENGTH, { message: 'Password must not exceed 32 characters' })
  @Matches(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).+$/, {
    message:
      'Password must contain upper, lower, number, and special character',
  })
  password: string;
}
