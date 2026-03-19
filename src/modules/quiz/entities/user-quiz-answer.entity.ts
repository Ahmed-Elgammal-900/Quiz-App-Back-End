import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  Unique,
} from 'typeorm';
import { Quiz } from './quiz.entity';
import { Answer } from './answer.entity';
import { Question } from './question.entity';
import { User } from '../../user/entities/user.entity';

@Entity('user_quiz_answers')
@Unique(['userId', 'quizId', 'questionId'])
export class UserQuizAnswer {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid', nullable: false })
  userId: string;

  @Column({ type: 'uuid', nullable: false })
  quizId: string;

  @Column({ type: 'uuid', nullable: false })
  questionId: string;

  @Column({ type: 'uuid', nullable: false })
  selectedAnswerId: string;

  @Column({ type: 'boolean', default: false })
  isCorrect: boolean;

  @ManyToOne(() => Quiz, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'quizId' })
  quiz: Quiz;

  @ManyToOne(() => Question, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'questionId' })
  question: Question;

  @ManyToOne(() => Answer, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'selectedAnswerId' })
  selectedAnswer: Answer;

  @ManyToOne(() => User, (user) => user.quizAnswers, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user: User;
}
