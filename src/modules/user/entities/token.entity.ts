import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  Index,
} from 'typeorm';
import { User } from './user.entity';
import { TokenType } from '../../auth/constants/token-type.constant';

@Entity()
@Index(['userId', 'type'], { unique: true })
export class Token {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  @Index()
  token: string;

  @Column({ type: 'enum', enum: TokenType })
  type: TokenType;

  @Column()
  expiresAt: Date;

  @Column({ default: 0 })
  attempts: number;

  @Column({ nullable: true })
  lastSentAt: Date;

  @CreateDateColumn()
  createdAt: Date;

  @ManyToOne(() => User, (user) => user.tokens, { onDelete: 'CASCADE' })
  @JoinColumn()
  user: User;

  @Column()
  userId: string;
}
