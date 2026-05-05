import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '../modules/user/entities/user.entity';
import { DeletedUser } from '../modules/user/entities/deletedUser.entity';
import { Token } from '../modules/user/entities/token.entity';
import { Quiz } from '../modules/quiz/entities/quiz.entity';
import { Answer } from '../modules/quiz/entities/answer.entity';
import { Question } from '../modules/quiz/entities/question.entity';
import { UserQuizProgress } from '../modules/quiz/entities/user-progress.entity';
import { UserQuizAnswer } from '../modules/quiz/entities/user-quiz-answer.entity';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres' as const,
        url: configService.get<string>('DATABASE_URL'),
        entities: [
          User,
          DeletedUser,
          Token,
          Quiz,
          Answer,
          Question,
          UserQuizProgress,
          UserQuizAnswer,
        ],
        synchronize: true,
        ssl: {
          rejectUnauthorized: false,
        },
      }),
    }),
  ],
})
export class Database {}
