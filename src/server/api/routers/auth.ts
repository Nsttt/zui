import { z } from "zod";
import { createTRPCRouter, protectedProcedure } from "../trpc";
import { prisma } from "@/server/db";

export const CreateUserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(4),
  name: z.string(),
});

export const authRouter = createTRPCRouter({
  createUser: protectedProcedure.input(CreateUserSchema).mutation(
    async ({ input }) =>
      await prisma.user.create({
        data: {
          email: input.email,
          name: input.name,
          password: input.password,
        },
      })
  ),
});
