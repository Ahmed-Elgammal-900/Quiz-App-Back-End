import { IsEmail, IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class GoogleDto {
  @ApiProperty({
    description: 'Full name from Google account',
    example: 'John Doe',
  })
  @IsNotEmpty()
  @IsString()
  name!: string;

  @ApiProperty({
    description: 'Email address from Google account',
    example: 'johndoe@gmail.com',
  })
  @IsNotEmpty()
  @IsEmail()
  email!: string;

  @ApiProperty({
    description: 'Unique Google account identifier',
    example: '108839473920484757263',
  })
  @IsNotEmpty()
  @IsString()
  googleId!: string;
}
