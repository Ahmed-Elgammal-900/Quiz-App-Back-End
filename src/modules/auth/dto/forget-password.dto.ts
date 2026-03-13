import { PickType } from '@nestjs/mapped-types';
import { CreateAuthDto } from './signup.dto';

export class ForgetPasswordDto extends PickType(CreateAuthDto, [
  'email',
] as const) {}
