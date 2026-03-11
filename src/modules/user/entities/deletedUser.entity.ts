import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
} from 'typeorm';

@Entity()
export class DeletedUser {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ nullable: false })
  email: string;

  @CreateDateColumn()
  deletedAt: Date;
}
