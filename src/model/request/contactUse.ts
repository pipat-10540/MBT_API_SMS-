import { Schema, z } from "zod";
export const contactSchema = z.object({
  id: z.number().optional(),
  user_id: z.number().optional(),
  first_name: z.string().optional(),
  last_name: z.string().optional(),
  phone: z.string().optional(),
  email: z.string().optional(),
  birth_date: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/)
    .optional(),
  group_id: z.number().optional(),
  group_name: z.string().optional(),
  status: z.boolean().optional(),
  create_date: z.string().optional(),
  last_update: z.string().optional(),
});

export const DeleteSchema = z.object({
  id: z.array(z.number()),
});
export type contact = z.infer<typeof contactSchema>;
