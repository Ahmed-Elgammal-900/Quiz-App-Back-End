import { Entity, PrimaryGeneratedColumn, Column, OneToMany } from 'typeorm';
import { Token } from '../../user/entities/token.entity';
import { Provider } from '../constants/provider.constant';
import { UserQuizProgress } from '../../quiz/entities/user-progress.entity';
import { UserQuizAnswer } from '../../quiz/entities/user-quiz-answer.entity';

@Entity()
export class User {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column()
  name!: string;

  @Column({ unique: true })
  email!: string;

  @Column({ nullable: true, type: 'text' })
  password!: string | null;

  @Column({ nullable: true, type: 'text' })
  googleId!: string | null;

  @Column({
    type: 'simple-array',
    default: Provider.LOCAL,
  })
  providers!: Provider[];

  @Column({ default: false })
  isEmailVerified!: boolean;

  @OneToMany(() => Token, (token) => token.user)
  tokens!: Token[];

  @OneToMany(() => UserQuizProgress, (progress) => progress.user, {
    cascade: true,
  })
  quizProgresses!: UserQuizProgress[];

  @OneToMany(() => UserQuizAnswer, (answer) => answer.user, {
    cascade: true,
  })
  quizAnswers!: UserQuizAnswer[];
}
