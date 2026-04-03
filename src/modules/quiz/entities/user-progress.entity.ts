import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  Unique,
  Index,
} from 'typeorm';
import { Quiz } from './quiz.entity';
import { Question } from './question.entity';
import { QuizProgressStatus } from '../constants/quiz-progress-status';
import { User } from '../../user/entities/user.entity';

@Entity('user_quiz_progress')
@Unique(['userId', 'quizId'])
@Index(['userId', 'status'])
export class UserQuizProgress {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid', nullable: false })
  userId!: string;

  @Column({ type: 'uuid', nullable: false })
  quizId!: string;

  @Column({
    type: 'enum',
    enum: QuizProgressStatus,
    default: QuizProgressStatus.IN_PROGRESS,
  })
  status!: QuizProgressStatus;

  @Column({ type: 'uuid', nullable: true })
  pausedAtQuestionId!: string | null;

  @Column({ type: 'numeric', precision: 5, scale: 2, nullable: true })
  score!: number | null;

  @Column({ type: 'boolean', default: false })
  passed!: boolean;

  @Column({ type: 'int', nullable: true, default: null })
  remainingTimeSeconds!: number | null;

  @Column({ type: 'timestamptz', nullable: true })
  attemptAt!: Date | null;

  @Column({ type: 'timestamptz', nullable: true })
  completedAt!: Date | null;

  @ManyToOne(() => Quiz, { onDelete: 'CASCADE', nullable: false })
  @JoinColumn({ name: 'quizId' })
  quiz!: Quiz;

  @ManyToOne(() => Question, { onDelete: 'SET NULL', nullable: true })
  @JoinColumn({ name: 'pausedAtQuestionId' })
  pausedAtQuestion!: Question | null;

  @ManyToOne(() => User, (user) => user.quizProgresses, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user!: User;
}
