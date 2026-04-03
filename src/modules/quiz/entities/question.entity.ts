import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  OneToMany,
  JoinColumn,
  Index,
} from 'typeorm';
import { Quiz } from './quiz.entity';
import { Answer } from './answer.entity';

@Entity('questions')
@Index(['quizId'])
export class Question {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid' })
  quizId!: string;

  @Column({ type: 'text' })
  text!: string;

  @Column({ type: 'int', default: 0 })
  orderIndex!: number;

  @ManyToOne(() => Quiz, (quiz) => quiz.questions, {
    onDelete: 'CASCADE',
    nullable: false,
  })
  @JoinColumn({ name: 'quizId' })
  quiz!: Quiz;

  @OneToMany(() => Answer, (answer) => answer.question, {
    cascade: true,
    eager: false,
  })
  answers!: Answer[];
}
