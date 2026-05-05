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
import { QuizProgressStatus } from '../constants/quiz-progress-status';
import { User } from '../../user/entities/user.entity';

@Entity('user_quiz_progress')
@Unique(['userId', 'quizId'])
@Index(['userId', 'status'])
export class UserQuizProgress {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @ManyToOne(() => Quiz, { onDelete: 'CASCADE', nullable: false })
  @JoinColumn({ name: 'quizId' })
  quiz!: Quiz;

  @Column({ name: 'quizId', type: 'uuid' })
  quizId!: string;

  @ManyToOne(() => User, (user) => user.quizProgresses, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user!: User;

  @Column({ name: 'userId', type: 'uuid' })
  userId!: string;

  @Column({ name: 'pausedAtQuestionIndex', type: 'int', default: 0 })
  pausedAtQuestionIndex!: number;

  @Column({
    type: 'enum',
    enum: QuizProgressStatus,
  })
  status!: QuizProgressStatus;

  @Column({
    type: 'numeric',
    precision: 5,
    scale: 2,
    nullable: true,
    transformer: {
      to: (value: number) => value,
      from: (value: string) => (value == null ? null : Number(value)),
    },
  })
  score!: number | null;

  @Column({ type: 'boolean', default: false })
  passed!: boolean;

  @Column({ type: 'int', default: 0 })
  remainingTimeSeconds!: number;

  @Column({ type: 'int', nullable: true })
  progress!: number | null;

  @Column({ type: 'timestamptz', nullable: true })
  attemptAt!: Date | null;

  @Column({ type: 'timestamptz', nullable: true })
  completedAt!: Date | null;
}
