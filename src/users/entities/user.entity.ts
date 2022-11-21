import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import Audit from '../../shared/interface/audit.entity';
import { ApiProperty } from '@nestjs/swagger';

@Entity()
export class User extends Audit {
  @ApiProperty()
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty()
  @Column({ unique: true, nullable: false })
  email: string;

  @Column({ nullable: false })
  password?: string;

  @ApiProperty()
  @Column({ name: 'first_name' })
  firstName: string;

  @ApiProperty()
  @Column({ name: 'last_name' })
  lastName: string;

  @ApiProperty()
  @Column({ nullable: true })
  gender: string;

  @ApiProperty()
  @Column({ name: 'phone_number', unique: true, nullable: false })
  phoneNumber: string;

  @ApiProperty()
  @Column({ default: false, nullable: true })
  isVerified: boolean;
}
