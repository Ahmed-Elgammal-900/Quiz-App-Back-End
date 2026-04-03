import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { Question } from './question.entity';

@Entity('answers')
@Index(['questionId'])
export class Answer {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid' })
  questionId!: string;

  @Column({ type: 'varchar', length: 1000 })
  text!: string;

  @Column({ type: 'boolean', default: false })
  isCorrect!: boolean;

  @Column({ type: 'int', default: 0 })
  orderIndex!: number;

  @ManyToOne(() => Question, (question) => question.answers, {
    onDelete: 'CASCADE',
    nullable: false,
  })
  @JoinColumn({ name: 'questionId' })
  question!: Question;
}
