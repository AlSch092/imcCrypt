//By AlSch092 @ Github
#include "imcCrypt.hpp"

unsigned short __declspec(naked) imcCrypt::MakeChecksum(LPBYTE outBuffer, const UINT uiSize)
{
	__asm
	{
			push ebp
			mov ebp, esp
			push edi
			mov edi, [ebp + 0x08]
			xor edx, edx
			test edi, edi
			jne case7
			xor eax, eax
			jmp case6
	case7:
			push esi
			mov esi, edx
			cmp[ebp + 0x0C], edx
			jle case5
	case1:
			mov eax, esi
			and eax, 0x80000001
			jns case4
			dec eax
			or eax, -02
			inc eax
	case4:
			je case3
			movzx eax, byte ptr[esi + edi]
			add edx, eax
			jmp case2
	case3:
			movzx ecx, byte ptr[esi + edi]
			xor edx, ecx
	case2:
			inc esi
			cmp esi, [ebp + 0x0C]
			jl case1
	case5:
			mov eax, edx
			pop esi
	case6:
			pop edi
			pop ebp
			ret
	}
}

extern "C" int __declspec(dllexport) AddChecksumToPacket(LPBYTE outBuffer, const UINT uiSize)
{
	unsigned short checksum = imcCrypt::MakeChecksum(outBuffer, uiSize);
	memcpy((void*)(outBuffer + 6), (void*)&checksum, 2);
	return checksum;
}

extern "C" int __declspec(dllexport) Encrypt(LPBYTE pBuf, LPBYTE outBuffer , const UINT uiSize)
{
	return imcCrypt::Encrypt(pBuf, outBuffer, uiSize, imcCrypt::key); //(imcCrypt::bf_key_st*)0x00F83BD8	
}

int __declspec(naked) imcCrypt::GetNumBlock(const int dataLen) //convert back to c when test done
{
	__asm
	{
		push ebp
		mov ebp, esp
		push esi
		mov esi, [ebp + 0x08]
		mov eax, esi
		cdq
		and edx, 0x07
		add eax, edx
		sar eax, 0x03
		mov ecx, eax
		shl ecx, 0x03
		sub esi, ecx
		test esi, esi
		pop esi
		jle jmp1
		inc eax
	jmp1:
		pop ebp
		ret

	}
}

void __declspec(naked) _memcpy(const unsigned __int8 *pDataIn, unsigned __int8 *pDataOut, const int dataLen) //preserve the stack
{
	memcpy((void*)pDataOut, pDataIn, dataLen);

	__asm
	{
		ret
	}
}

UINT16 __declspec(naked) imcCrypt::_BF_encrypt(LPVOID inBuffer, LPVOID key) //2 arguments
{
	__asm
	{
			push ebp
			push ebx
			mov ebx, [esp + 0x0C]
			mov ebp, [esp + 0x10]
			push esi
			push edi
			mov edi, [ebx]
			mov esi, [ebx + 0x04]
			xor eax, eax
			mov ebx, [ebp + 0x00]
			xor ecx, ecx
			xor edi, ebx
			mov edx, [ebp + 0x04]
			mov ebx, edi
			xor esi, edx
			shr ebx, 0x10
			mov edx, edi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor esi, ebx
			mov edx, [ebp + 0x08]
			mov ebx, esi
			xor edi, edx
			shr ebx, 0x10
			mov edx, esi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor edi, ebx
			mov edx, [ebp + 0x0C]
			mov ebx, edi
			xor esi, edx
			shr ebx, 0x10
			mov edx, edi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor esi, ebx
			mov edx, [ebp + 0x10]
			mov ebx, esi
			xor edi, edx
			shr ebx, 0x10
			mov edx, esi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor edi, ebx
			mov edx, [ebp + 0x14]
			mov ebx, edi
			xor esi, edx
			shr ebx, 0x10
			mov edx, edi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor esi, ebx
			mov edx, [ebp + 0x18]
			mov ebx, esi
			xor edi, edx
			shr ebx, 0x10
			mov edx, esi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor edi, ebx
			mov edx, [ebp + 0x1C]
			mov ebx, edi
			xor esi, edx
			shr ebx, 0x10
			mov edx, edi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor esi, ebx
			mov edx, [ebp + 0x20]
			mov ebx, esi
			xor edi, edx
			shr ebx, 0x10
			mov edx, esi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor edi, ebx
			mov edx, [ebp + 0x24]
			mov ebx, edi
			xor esi, edx
			shr ebx, 0x10
			mov edx, edi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor esi, ebx
			mov edx, [ebp + 0x28]
			mov ebx, esi
			xor edi, edx
			shr ebx, 0x10
			mov edx, esi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor edi, ebx
			mov edx, [ebp + 0x2C]
			mov ebx, edi
			xor esi, edx
			shr ebx, 0x10
			mov edx, edi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor esi, ebx
			mov edx, [ebp + 0x30]
			mov ebx, esi
			xor edi, edx
			shr ebx, 0x10
			mov edx, esi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor edi, ebx
			mov edx, [ebp + 0x34]
			mov ebx, edi
			xor esi, edx
			shr ebx, 0x10
			mov edx, edi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor esi, ebx
			mov edx, [ebp + 0x38]
			mov ebx, esi
			xor edi, edx
			shr ebx, 0x10
			mov edx, esi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor edi, ebx
			mov edx, [ebp + 0x3C]
			mov ebx, edi
			xor esi, edx
			shr ebx, 0x10
			mov edx, edi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor esi, ebx
			mov edx, [ebp + 0x40]
			mov ebx, esi
			xor edi, edx
			shr ebx, 0x10
			mov edx, esi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			mov eax, [esp + 0x14]
			xor edi, ebx
			mov edx, [ebp + 0x44]
			xor esi, edx
			mov[eax + 0x04], edi
			mov[eax], esi
			pop edi
			pop esi
			pop ebx
			pop ebp
			ret

	}
}

UINT16 __declspec(naked) imcCrypt::_BF_decrypt(LPVOID inBuffer, LPVOID key)
{
	__asm
	{
			push ebp
			push ebx
			mov ebx, [esp + 0x0C]
			mov ebp, [esp + 0x10]
			push esi
			push edi
			mov edi, [ebx]
			mov esi, [ebx + 0x04]
			xor eax, eax
			mov ebx, [ebp + 0x44]
			xor ecx, ecx
			xor edi, ebx
			mov edx, [ebp + 0x40]
			mov ebx, edi
			xor esi, edx
			shr ebx, 0x10
			mov edx, edi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor esi, ebx
			mov edx, [ebp + 0x3C]
			mov ebx, esi
			xor edi, edx
			shr ebx, 0x10
			mov edx, esi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor edi, ebx
			mov edx, [ebp + 0x38]
			mov ebx, edi
			xor esi, edx
			shr ebx, 0x10
			mov edx, edi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor esi, ebx
			mov edx, [ebp + 0x34]
			mov ebx, esi
			xor edi, edx
			shr ebx, 0x10
			mov edx, esi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor edi, ebx
			mov edx, [ebp + 0x30]
			mov ebx, edi
			xor esi, edx
			shr ebx, 0x10
			mov edx, edi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor esi, ebx
			mov edx, [ebp + 0x2C]
			mov ebx, esi
			xor edi, edx
			shr ebx, 0x10
			mov edx, esi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor edi, ebx
			mov edx, [ebp + 0x28]
			mov ebx, edi
			xor esi, edx
			shr ebx, 0x10
			mov edx, edi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor esi, ebx
			mov edx, [ebp + 0x24]
			mov ebx, esi
			xor edi, edx
			shr ebx, 0x10
			mov edx, esi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor edi, ebx
			mov edx, [ebp + 0x20]
			mov ebx, edi
			xor esi, edx
			shr ebx, 0x10
			mov edx, edi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor esi, ebx
			mov edx, [ebp + 0x1C]
			mov ebx, esi
			xor edi, edx
			shr ebx, 0x10
			mov edx, esi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor edi, ebx
			mov edx, [ebp + 0x18]
			mov ebx, edi
			xor esi, edx
			shr ebx, 0x10
			mov edx, edi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor esi, ebx
			mov edx, [ebp + 0x14]
			mov ebx, esi
			xor edi, edx
			shr ebx, 0x10
			mov edx, esi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor edi, ebx
			mov edx, [ebp + 0x10]
			mov ebx, edi
			xor esi, edx
			shr ebx, 0x10
			mov edx, edi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor esi, ebx
			mov edx, [ebp + 0x0C]
			mov ebx, esi
			xor edi, edx
			shr ebx, 0x10
			mov edx, esi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor edi, ebx
			mov edx, [ebp + 0x08]
			mov ebx, edi
			xor esi, edx
			shr ebx, 0x10
			mov edx, edi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			xor eax, eax
			xor esi, ebx
			mov edx, [ebp + 0x04]
			mov ebx, esi
			xor edi, edx
			shr ebx, 0x10
			mov edx, esi
			mov al, bh
			and ebx, 0x000000FF
			mov cl, dh
			and edx, 0x000000FF
			mov eax, [ebp + eax * 4 + 0x48]
			mov ebx, [ebp + ebx * 4 + 0x00000448]
			add ebx, eax
			mov eax, [ebp + ecx * 4 + 0x00000848]
			xor ebx, eax
			mov edx, [ebp + edx * 4 + 0x00000C48]
			add ebx, edx
			mov eax, [esp + 0x14]
			xor edi, ebx
			mov edx, [ebp + 0x00]
			xor esi, edx
			mov[eax + 0x04], edi
			mov[eax], esi
			pop edi
			pop esi
			pop ebx
			pop ebp
			ret
	}
}

int __declspec(naked) imcCrypt::Encrypt(const unsigned __int8 *pDataIn, unsigned __int8 *pDataOut, const int dataLen, const bf_key_st *key) //0x00F83BD8
{
	__asm
	{
			push ebp
			mov ebp, esp
			push ebx
			push esi
			push edi
			push[ebp + 0x10]
			call GetNumBlock
			push[ebp + 0x10]
			mov esi, [ebp + 0x0C]
			mov edi, eax
			push[ebp + 0x08]
			mov ebx, edi
			push esi
			shl ebx, 03
			call _memcpy  ; in year 2024, i cant remember why we had to call our own memcpy, but it was definitely for a good reason.
			add esp, 0x10
			test edi, edi
			jle case1
	jump1 :
			push 1
			push[ebp + 0x14]
			push esi
			push esi
			call imcCrypt::_BF_ebc_encrypt
			add esp, 0x10
			add esi, 0x08
			dec edi
			jne jump1
	case1 :
			pop edi
			pop esi
			mov eax, ebx
			pop ebx
			pop ebp
			ret
	}
}

UINT16 __declspec(naked) imcCrypt::_BF_ebc_encrypt(LPBYTE data, int Length, LPVOID key, bool isEncrypting) //4 arguments, used for both encrypt and decrypt
{
	__asm
	{
			sub esp, 0x08
			mov eax, [esp + 0x0C]
			movzx ecx, byte ptr[eax]
			movzx edx, byte ptr[eax + 0x01]
			add eax, 01
			shl edx, 0x10
			shl ecx, 0x18
			or ecx, edx
			xor edx, edx
			mov dh, [eax + 0x01]
			add eax, 01
			add eax, 01
			add eax, 01
			add eax, 01
			add eax, 01
			or ecx, edx
			movzx edx, byte ptr[eax - 03]
			or ecx, edx
			movzx edx, byte ptr[eax - 01]
			mov [esp], ecx
			movzx ecx, byte ptr[eax - 02]
			shl edx, 0x10
			shl ecx, 0x18
			or ecx, edx
			xor edx, edx
			mov dh, [eax]
			mov dl, [eax + 0x01]	
			or edx, ecx
			cmp dword ptr[esp + 0x18], 00
			mov[esp + 0x04], edx
			je case1
			mov eax, [esp + 0x14]
			push eax
			lea ecx, [esp + 0x04]
			push ecx
			call imcCrypt::_BF_encrypt
			jmp jump1
case1:
			mov edx, [esp + 0x14]
			push edx
			lea eax, [esp + 0x04]
			push eax
			call imcCrypt::_BF_decrypt
jump1:
			mov ecx, [esp + 0x08]
			mov eax, [esp + 0x18]
			mov edx, ecx
			shr edx, 0x18
			mov[eax], dl
			add eax, 01
			mov edx, ecx
			shr edx, 0x10
			mov[eax], dl
			add eax, 01
			mov edx, ecx
			shr edx, 0x08
			mov[eax], dl
			mov[eax + 0x01], cl
			mov ecx, [esp + 0x0C]
			add eax, 01
			add eax, 01
			mov edx, ecx
			shr edx, 0x18
			mov[eax], dl
			add eax, 01
			mov edx, ecx
			shr edx, 0x10
			mov[eax], dl
			add eax, 01
			mov edx, ecx
			add esp, 0x08
			shr edx, 0x08
			mov[eax], dl
			mov[eax + 0x01], cl
			add esp, 0x08
			ret
	}

}