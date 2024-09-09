import { BadRequestException, Injectable, InternalServerErrorException } from '@nestjs/common';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import * as bcryptjs from 'bcryptjs'

import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterUserDto } from './dto/register-user.dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    private jwtService: JwtService
  ) { }

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      const { password, ...userData } = createUserDto;
      //encriptar password
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      })

      //crear user
      await newUser.save();

      // return response
      const { password: _, ...result } = newUser.toJSON();
      return result;
    } catch (error) {
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} already exists`);
      } else {
        throw new InternalServerErrorException("Something went wrong");
      }
    }
  }

  async register(registerUserDto: RegisterUserDto): Promise<LoginResponse> {
    try {
      const { email, name, password } = registerUserDto;
      const newUser: CreateUserDto = { email, name, password };
      const user = await this.create(newUser);
      return {
        user,
        token: await this.getJwtToken({ id: user._id })
      }
    } catch (error) {
      return error
    }
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {

    const { email, password } = loginDto;

    //Verificar si el usuario existe
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new BadRequestException("User not found");
    }

    //verificar si el password es correcto
    if (!bcryptjs.compareSync(password, user.password)) {
      throw new BadRequestException("Wrong password");
    }

    const { password: _, ...rest } = user.toJSON();

    return {
      user: rest,
      token: await this.getJwtToken({ id: user.id })
    };
  }



  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(id: string) {
    const user = await this.userModel.findById(id);
    const { password, ...result } = user.toJSON();
    return result;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  async getJwtToken(payload: JwtPayload) {
    const token = await this.jwtService.signAsync(payload);
    return token;
  }
}
