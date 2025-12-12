'use server';

import { z } from 'zod';
import { sql } from '@vercel/postgres';
import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { signIn } from '@/auth';
import { AuthError } from 'next-auth';
import { validatePayloadSize } from './monitoring';

// 🔒 Schémas de validation renforcés (protection CVE-2025-55183/55184)
const FormSchema = z.object({
    id: z.string(),
    customerId: z.string({
      invalid_type_error: 'Please select a customer.',
    }).min(1, { message: 'Customer ID is required.' }),
    amount: z.coerce
      .number()
      .gt(0, { message: 'Please enter an amount greater than $0.' })
      .lte(1000000, { message: 'Amount cannot exceed $1,000,000.' }), // Limite de sécurité
    status: z.enum(['pending', 'paid'], {
      invalid_type_error: 'Please select an invoice status.',
    }),
    date: z.string(),
});

// 🛡️ Validation stricte pour l'ID (protection contre injection)
const IdSchema = z.string().uuid({ message: 'Invalid ID format.' });

// 🔒 Schéma de validation pour l'authentification
const AuthSchema = z.object({
  email: z.string().email('Invalid email address.').max(255, 'Email too long.'),
  password: z.string().min(6, 'Password must be at least 6 characters.').max(255, 'Password too long.'),
});
   
const CreateInvoice = FormSchema.omit({ id: true, date: true });

export type State = {
    errors?: {
      customerId?: string[];
      amount?: string[];
      status?: string[];
    };
    message?: string | null;
};

export async function createInvoice(prevState: State, formData: FormData) {
    const startTime = Date.now();
    
    // 🛡️ Validation de la taille du payload (protection CVE-2025-55184)
    if (!validatePayloadSize(formData)) {
      console.log('[createInvoice] Payload too large');
      return {
        message: 'Request payload too large.',
      };
    }

    // Validate form using Zod
    const validatedFields = CreateInvoice.safeParse({
      customerId: formData.get('customerId'),
      amount: formData.get('amount'),
      status: formData.get('status'),
    });

    console.log(validatedFields);
    
    // If form validation fails, return errors early. Otherwise, continue.
    if (!validatedFields.success) {
      return {
        errors: validatedFields.error.flatten().fieldErrors,
        message: 'Missing Fields. Failed to Create Invoice.',
      };
    }
   
    // Prepare data for insertion into the database
    const { customerId, amount, status } = validatedFields.data;
    const amountInCents = amount * 100;
    const date = new Date().toISOString().split('T')[0];
   
    // Insert data into the database
    try {
      await sql`
        INSERT INTO invoices (customer_id, amount, status, date)
        VALUES (${customerId}, ${amountInCents}, ${status}, ${date})
      `;
      console.log(`[createInvoice] Success in ${Date.now() - startTime}ms`);
    } catch (error) {
      // 🔍 Log détaillé des erreurs pour monitoring
      console.error('[createInvoice] Database error:', error);
      return {
        message: 'Database Error: Failed to Create Invoice.',
      };
    }
   
    // Revalidate the cache for the invoices page and redirect the user.
    revalidatePath('/dashboard/invoices');
    redirect('/dashboard/invoices');
  }

// Use Zod to update the expected types
const UpdateInvoice = FormSchema.omit({ id: true, date: true });
 
export async function updateInvoice(
    id: string,
    prevState: State,
    formData: FormData,
  ) {
    const startTime = Date.now();
    
    // 🛡️ Validation de l'ID (protection CVE-2025-55183)
    const validatedId = IdSchema.safeParse(id);
    if (!validatedId.success) {
      console.log('[updateInvoice] Invalid ID format');
      return {
        message: 'Invalid ID format.',
      };
    }

    // 🛡️ Validation de la taille du payload
    if (!validatePayloadSize(formData)) {
      console.log('[updateInvoice] Payload too large');
      return {
        message: 'Request payload too large.',
      };
    }

    const validatedFields = UpdateInvoice.safeParse({
      customerId: formData.get('customerId'),
      amount: formData.get('amount'),
      status: formData.get('status'),
    });
   
    if (!validatedFields.success) {
      return {
        errors: validatedFields.error.flatten().fieldErrors,
        message: 'Missing Fields. Failed to Update Invoice.',
      };
    }
   
    const { customerId, amount, status } = validatedFields.data;
    const amountInCents = amount * 100;
   
    try {
      await sql`
        UPDATE invoices
        SET customer_id = ${customerId}, amount = ${amountInCents}, status = ${status}
        WHERE id = ${validatedId.data}
      `;
      console.log(`[updateInvoice] Success in ${Date.now() - startTime}ms`);
    } catch (error) {
      console.error('[updateInvoice] Database error:', error);
      return { message: 'Database Error: Failed to Update Invoice.' };
    }
   
    revalidatePath('/dashboard/invoices');
    redirect('/dashboard/invoices');
  }

export async function deleteInvoice(id: string) {
    // 🛡️ Validation de l'ID
    const validatedId = IdSchema.safeParse(id);
    if (!validatedId.success) {
      return { message: 'Invalid ID format.' };
    }

    try {
        await sql`DELETE FROM invoices WHERE id = ${validatedId.data}`;
        revalidatePath('/dashboard/invoices');
        return { message: 'Deleted Invoice.' };
      } catch (error) {
        console.error('[deleteInvoice] Database error:', error);
        return { message: 'Database Error: Failed to Delete Invoice.' };
      }
}

export async function deleteInvoiceAction(id: string) {
    // 🛡️ Validation de l'ID
    const validatedId = IdSchema.safeParse(id);
    if (!validatedId.success) {
      throw new Error('Invalid ID format.');
    }

    try {
        await sql`DELETE FROM invoices WHERE id = ${validatedId.data}`;
        revalidatePath('/dashboard/invoices');
    } catch (error) {
        console.error('[deleteInvoiceAction] Database error:', error);
        throw new Error('Database Error: Failed to Delete Invoice.');
    }
}

export async function authenticate(
    prevState: string | undefined,
    formData: FormData,
  ) {
    const startTime = Date.now();
    
    // 🛡️ Validation des credentials (protection CVE-2025-55183)
    const validatedCredentials = AuthSchema.safeParse({
      email: formData.get('email'),
      password: formData.get('password'),
    });

    if (!validatedCredentials.success) {
      console.log('[authenticate] Invalid input format');
      return 'Invalid input format.';
    }

    try {
      await signIn('credentials', formData);
      console.log(`[authenticate] Success in ${Date.now() - startTime}ms`);
    } catch (error) {
      console.error('[authenticate] Auth error:', error);
      if (error instanceof AuthError) {
        switch (error.type) {
          case 'CredentialsSignin':
            return 'Invalid credentials.';
          default:
            return 'Something went wrong.';
        }
      }
      throw error;
    }
  }

