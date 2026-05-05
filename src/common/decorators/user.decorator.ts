import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { UserResponse } from '@/modules/auth/types/response-types';

export const CurrentUser = createParamDecorator(
  (data: keyof UserResponse, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;

    return data ? user?.[data] : user;
  },
);
