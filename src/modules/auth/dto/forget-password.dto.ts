import { PickType } from '@nestjs/mapped-types';
import { CreateAuthDto } from './signup.dto';

export class UpdateAuthDto extends PickType(CreateAuthDto, [
  'email',
] as const) {}
