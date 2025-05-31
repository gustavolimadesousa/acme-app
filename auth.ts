import NextAuth from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { authConfig } from "./auth.config";
import { z } from "zod";
import bcrypt from "bcrypt";
import postgres from "postgres";
import type { User } from "@/app/lib/definitions";

// Inicializa conexão com o banco de dados
const sql = postgres(process.env.POSTGRES_URL!, { ssl: "require" });

// Define schema para validação com Zod
const credentialsSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1, "Password is required"),
});

// Função auxiliar para buscar usuário no banco
async function getUserByEmail(email: string): Promise<User | null> {
  const result = await sql<User[]>`
    SELECT * FROM users WHERE email = ${email}
  `;
  return result[0] ?? null;
}

// Configura autenticação
export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    CredentialsProvider({
      name: "Credentials",
      async authorize(credentials) {
        // Valida as credenciais com Zod
        const parsed = credentialsSchema.safeParse(credentials);
        if (!parsed.success) {
          console.log("Validation failed:", parsed.error.flatten());
          return null;
        }

        const { email, password } = parsed.data;

        try {
          const user = await getUserByEmail(email);
          if (!user) {
            console.log("User not found");
            return null;
          }

          const isPasswordValid = await bcrypt.compare(password, user.password);
          if (!isPasswordValid) {
            console.log("Incorrect password");
            return null;
          }

          // Remove a senha do retorno por segurança
          const { password: _, ...userWithoutPassword } = user;
          return userWithoutPassword;
        } catch (error) {
          console.error("Authorization error:", error);
          return null;
        }
      },
    }),
  ],
});
