import { Entity, PrimaryGeneratedColumn, Column, OneToMany } from 'typeorm';
import { Token } from 'src/modules/user/entities/token.entity';
import { Provider } from '../constants/provider.constant';

@Entity()
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  name: string;

  @Column({ unique: true })
  email: string;

  @Column({ nullable: true })
  password: string;

  @Column({ nullable: true })
  googleId: string;

  @Column({
    type: 'simple-array',
    default: Provider.LOCAL,
  })
  providers: Provider[];

  @Column({ default: false })
  isEmailVerified: boolean;

  @OneToMany(() => Token, (token) => token.user)
  tokens: Token[];
}
