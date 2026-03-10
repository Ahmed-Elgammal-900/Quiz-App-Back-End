import { OmitType } from '@nestjs/mapped-types';
import { CreateAuthDto } from './signup.dto';

export class LoginDto extends OmitType(CreateAuthDto, ['name'] as const) {}
