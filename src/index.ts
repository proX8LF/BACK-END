import express, { Request, Response, Application } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import path from 'path';
import fs from 'fs/promises';
import cors from 'cors';

interface User {
  id: number;
  username: string;
  email: string;
  password: string;
  role: string;
}

const app: Application = express();
const port: number = 3001;

const USERS_FILE = path.join(__dirname, '../users.json');
const JWT_SECRET: string = 'e6b8f8d4a7c9b2e5f1d0a3c8e9b7f4d2';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

async function loadUsers(): Promise<User[]> {
  try {
    const data = await fs.readFile(USERS_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    return [];
  }
}

async function saveUser(user: User): Promise<void> {
  const users = await loadUsers();
  users.push(user);
  await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), 'utf-8');
}

app.post('/api/register', async (req: Request, res: Response): Promise<void> => {
  const { username, email, password } = req.body;
  try {
    const users = await loadUsers();
    if (users.some((u) => u.username === username || u.email === email)) {
      res.status(400).json({ error: 'المستخدم موجود بالفعل' });
      return;
    }

    const hashedPassword: string = await bcrypt.hash(password, 10);
    const newUser: User = {
      id: users.length + 1,
      username,
      email,
      password: hashedPassword,
      role: 'customer',
    };

    await saveUser(newUser);
    res.status(201).json({ message: 'تم إنشاء المستخدم' });
  } catch (error) {
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

app.post('/api/login', async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body;
  try {
    const users = await loadUsers();
    const user = users.find((u) => u.email === email);
    if (!user) {
      res.status(400).json({ error: 'المستخدم غير موجود' });
      return;
    }

    const valid: boolean = await bcrypt.compare(password, user.password);
    if (!valid) {
      res.status(400).json({ error: 'كلمة المرور غير صحيحة' });
      return;
    }

    const token: string = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

app.listen(port, () => {
  console.log(`الخادم يعمل على http://localhost:${port}`);
});