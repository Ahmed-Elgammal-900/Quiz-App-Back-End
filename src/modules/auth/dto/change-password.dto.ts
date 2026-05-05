import {
  IsString,
  MinLength,
  IsNotEmpty,
  MaxLength,
  Matches,
  IsOptional,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { Match } from '../../../common/decorators/match.decorator';
import {
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
} from '../constants/auth.constants';

export class UpdatePasswordDto {
  @ApiProperty({
    description: 'The current password of the user',
    example: 'OldPass@123',
    required: false,
  })
  @IsOptional()
  @IsString()
  @MinLength(1, { message: 'Current password cannot be empty if provided' })
  currentPassword?: string;

  @ApiProperty({
    description: `New password. Must be ${MIN_PASSWORD_LENGTH}–${MAX_PASSWORD_LENGTH} characters and contain uppercase, lowercase, number, and special character`,
    example: 'NewPass@456',
    minLength: MIN_PASSWORD_LENGTH,
    maxLength: MAX_PASSWORD_LENGTH,
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(MIN_PASSWORD_LENGTH, {
    message: `Password must be at least ${MIN_PASSWORD_LENGTH} characters long`,
  })
  @MaxLength(MAX_PASSWORD_LENGTH, {
    message: `Password must not exceed ${MAX_PASSWORD_LENGTH} characters`,
  })
  @Matches(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).+$/, {
    message:
      'Password must contain upper, lower, number, and special character',
  })
  newPassword!: string;

  @ApiProperty({
    description: 'Must match newPassword exactly',
    example: 'NewPass@456',
  })
  @IsNotEmpty()
  @IsString()
  @Match('newPassword', { message: 'Passwords do not match' })
  confirmPassword!: string;
}
