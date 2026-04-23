import { Injectable, ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { UserRole } from './enums/user-role.enum';
import * as bcrypt from 'bcrypt';
import { ConflictException } from '@nestjs/common';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private jwtService: JwtService,
  ) {}

  async validateUser(profile: any): Promise<User> {
    const { id, username, emails, photos, displayName } = profile;
    const email = emails && emails[0] ? emails[0].value : null;
    const avatarUrl = photos && photos[0] ? photos[0].value : null;

    let user = await this.userRepository.findOne({ where: { githubId: id.toString() } });

    if (!user) {
      // Try to match by email if available
      if (email) {
        user = await this.userRepository.findOne({ where: { email } });
      }

      if (user) {
        user.githubId = id.toString();
      } else {
        const userCount = await this.userRepository.count();
        const isFirstUser = userCount === 0;

        user = this.userRepository.create({
          githubId: id.toString(),
          username: username || email?.split('@')[0] || `user_${id}`,
          email,
          avatarUrl,
          displayName,
          role: isFirstUser ? UserRole.SUPERUSER : UserRole.USER,
          isActive: isFirstUser, // Only first user is active by default
        });
      }
      await this.userRepository.save(user);
    } else {
      // Update info if changed
      user.username = username || user.username;
      user.email = email || user.email;
      user.avatarUrl = avatarUrl || user.avatarUrl;
      user.displayName = displayName || user.displayName;
      await this.userRepository.save(user);
    }

    return user;
  }

  async validateKeycloakUser(profile: any): Promise<User> {
    const { id, username, emails, displayName } = profile;
    const email = emails && emails[0] ? emails[0].value : null;

    let user = await this.userRepository.findOne({ where: { keycloakId: id } });

    if (!user) {
      // Try to match by email if available
      if (email) {
        user = await this.userRepository.findOne({ where: { email } });
      }

      if (user) {
        user.keycloakId = id;
      } else {
        const userCount = await this.userRepository.count();
        const isFirstUser = userCount === 0;

        user = this.userRepository.create({
          keycloakId: id,
          username: username || email?.split('@')[0] || `user_${id}`,
          email,
          displayName,
          role: isFirstUser ? UserRole.SUPERUSER : UserRole.USER,
          isActive: isFirstUser, // Only first user is active by default
        });
      }
      await this.userRepository.save(user);
    } else {
      // Update info
      user.username = username || user.username;
      user.email = email || user.email;
      user.displayName = displayName || user.displayName;
      await this.userRepository.save(user);
    }

    return user;
  }

  async validateUserLocal(username: string, pass: string): Promise<any> {
    const user = await this.userRepository.findOne({ 
      where: { username },
      select: ['id', 'username', 'password', 'role', 'email', 'displayName', 'avatarUrl', 'isActive']
    });

    if (user && user.password && await bcrypt.compare(pass, user.password)) {
      if (!user.isActive) {
        throw new UnauthorizedException('Votre compte est en attente de validation par un administrateur.');
      }
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async registerUser(userData: any): Promise<User> {
    const { username, password, email, displayName } = userData;

    const userCount = await this.userRepository.count();
    const isFirstUser = userCount === 0;

    const existingUser = await this.userRepository.findOne({
      where: [{ username }, { email }],
    });

    if (existingUser) {
      throw new ConflictException('Username or email already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = this.userRepository.create({
      username,
      password: hashedPassword,
      email,
      displayName,
      role: isFirstUser ? UserRole.SUPERUSER : UserRole.USER,
      isActive: isFirstUser, // Only first user is active by default
    });

    return this.userRepository.save(user);
  }


  async login(user: User) {
    if (!user.isActive) {
      throw new UnauthorizedException('Votre compte est en attente de validation par un administrateur.');
    }
    const payload = { username: user.username, sub: user.id, role: user.role };
    return {
      access_token: this.jwtService.sign(payload),
      user,
    };
  }


  async canRegister(): Promise<boolean> {
    const userCount = await this.userRepository.count();
    return userCount === 0;
  }

  async findUserById(id: number): Promise<User | null> {
    return this.userRepository.findOne({ where: { id } });
  }
}

