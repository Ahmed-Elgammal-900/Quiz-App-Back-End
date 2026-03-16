import { Module } from '@nestjs/common';
import { QuizService } from './quiz.service';
import { QuizController } from './quiz.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Quiz } from './entities/quiz.entity';
import { Question } from './entities/question.entity';
import { Answer } from './entities/answer.entity';
import { UserQuizAnswer } from './entities/user-quiz-answer.entity';
import { UserQuizProgress } from './entities/user-progress.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      Quiz,
      Question,
      Answer,
      UserQuizAnswer,
      UserQuizProgress,
    ]),
  ],
  controllers: [QuizController],
  providers: [QuizService],
})
export class QuizModule {}
