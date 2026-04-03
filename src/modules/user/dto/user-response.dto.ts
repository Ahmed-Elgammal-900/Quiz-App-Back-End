import { Expose } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';

export class UserResponseDto {
  @ApiProperty({
    description: 'Unique identifier of the user',
    example: 'a3bb189e-8bf9-3888-9912-ace4e6543002',
  })
  @Expose()
  id!: string;

  @ApiProperty({
    description: 'Email address of the user',
    example: 'johndoe@gmail.com',
  })
  @Expose()
  email!: string;

  @ApiProperty({
    description: 'Full name of the user',
    example: 'John Doe',
  })
  @Expose()
  name!: string;

  @ApiProperty({
    description: 'Whether the user has verified their email address',
    example: true,
  })
  @Expose()
  isEmailVerified!: boolean;
}
