import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/modules/user/entities/user.entity';
import { DeletedUser } from 'src/modules/user/entities/deletedUser.entity';
import { Token } from 'src/modules/user/entities/token.entity';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        url: configService.get<string>('DATABASE_URL'),
        entities: [User, DeletedUser, Token],
        synchronize: false,
        ssl: {
          rejectUnauthorized: false,
        },
      }),
    }),
  ],
})
export class Database {}
