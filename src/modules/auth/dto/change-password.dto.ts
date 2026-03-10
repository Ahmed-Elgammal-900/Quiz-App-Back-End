import {
  IsString,
  MinLength,
  IsNotEmpty,
  MaxLength,
  Matches,
} from 'class-validator';
import { Match } from 'src/common/decorators/match.decorator';
import { MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH } from '../constants/auth.constants';

export class UpdatePasswordDto {
  @IsString()
  @IsNotEmpty()
  currentPassword: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(MIN_PASSWORD_LENGTH, { message: 'Password must be at least 8 characters long' })
  @MaxLength(MAX_PASSWORD_LENGTH, { message: 'Password must not exceed 32 characters' })
  @Matches(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).+$/, {
    message:
      'Password must contain upper, lower, number, and special character',
  })
  newPassword: string;

  @Match('password', { message: 'Passwords do not match' })
  confirmPassword: string;
}
