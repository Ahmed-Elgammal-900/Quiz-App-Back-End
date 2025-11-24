import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity()
export class DeletedUser {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({nullable: false})
  email: string;
}
