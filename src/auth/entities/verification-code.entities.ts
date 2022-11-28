import { User } from "src/users/entities/user.entity";
import { Column, Entity, ManyToOne, PrimaryGeneratedColumn } from "typeorm";

@Entity()
export class VerificationCode  {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ name: 'code', nullable: false })
  code: string;

  @Column({
    name: 'expiry_date',
    type: 'timestamptz',
    nullable: false,
    default: () => 'CURRENT_TIMESTAMP',
  })
  expiryDate: Date;

  @ManyToOne(() => User, (user: User) => user.email)
  user: User;
}