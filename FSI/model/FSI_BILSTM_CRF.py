import torch
import torch.nn as nn
import sys

from torch.nn.utils.rnn import pack_padded_sequence, pad_packed_sequence
from utils import common, config

class Highway(nn.Module):
    def __init__(self, size, num_layers=1, dropout=0.5):
        super(Highway, self).__init__()
        self.size = size
        self.num_layers = num_layers
        self.transform = nn.ModuleList()  # list of transform layers
        self.gate = nn.ModuleList()  # list of gate layers
        self.dropout = nn.Dropout(p=dropout)

        for i in range(num_layers):
            transform = nn.Linear(size, size)
            gate = nn.Linear(size, size)
            self.transform.append(transform)
            self.gate.append(gate)

    def forward(self, x):
        transformed = nn.functional.relu(self.transform[0](x))
        g = nn.functional.sigmoid(self.gate[0](x))
        out = g * transformed + (1-g)*x
        for i in range(1, self.num_layers):
            out = self.dropout(out)
            transformed = nn.functional.relu(self.transform[i](out))
            g = nn.functional.sigmoid(self.gate[i](out))
            out = g * transformed + (1-g) * out
        return out


class CRF(nn.Module):
    def __init__(self, hidden_dim, tagset_size):
        super(CRF, self).__init__()
        self.tagset_size = tagset_size
        self.emission = nn.Linear(hidden_dim, self.tagset_size)
        self.transition = nn.Parameter(torch.Tensor(self.tagset_size, self.tagset_size))
        self.transition.data.zero_()

    def forward(self, feats):
        self.batch_size = feats.size(0)
        self.timesteps = feats.size(1)

        emission_socres = self.emission(feats)
        emission_socres = emission_socres.unsqueeze(2).expand(self.batch_size, self.timesteps, self.tagset_size,
                                                              self.tagset_size)

        crf_scores = emission_socres + self.transition.unsqueeze(0).unsqueeze(0)
        return crf_scores


class FSI_BiLSTM_CRF(nn.Module):
    def __init__(self, tagset_size, instrset_size, instr_emb_dim, instr_rnn_dim, instr_rnn_layers, blokckset_size,
                 lm_vocab_size, block_emb_dim, block_rnn_dim, block_rnn_layers, dropout, highway_layers=1):
        super(FSI_BiLSTM_CRF, self).__init__()
        self.tagset_size = tagset_size

        self.instrset_size = instrset_size
        self.instr_emb_dim = instr_emb_dim
        self.instr_rnn_dim = instr_rnn_dim
        self.instr_rnn_layers = instr_rnn_layers

        self.blockset_size = blokckset_size
        self.block_emb_dim = block_emb_dim
        self.block_rnn_dim = block_rnn_dim
        self.block_rnn_layers = block_rnn_layers

        self.highway_layers = highway_layers

        self.lm_vocab_size = lm_vocab_size

        self.dropout = nn.Dropout(p=dropout)

        self.instr_embeds = nn.Embedding(self.instrset_size, self.instr_emb_dim)
        self.for_instr_lstm = nn.LSTM(self.instr_emb_dim, self.instr_rnn_dim, num_layers=self.instr_rnn_layers,
                                      bidirectional=False, dropout=dropout)
        self.back_instr_lstm = nn.LSTM(self.instr_emb_dim, self.instr_rnn_dim, num_layers=self.instr_rnn_layers,
                                       bidirectional=False, dropout=dropout)

        self.block_embeds = nn.Embedding(self.blockset_size, self.block_emb_dim)
        self.block_bilstm = nn.LSTM(self.block_emb_dim+self.instr_rnn_dim*2, self.block_rnn_dim,
                                  num_layers=self.block_rnn_layers, bidirectional=True, dropout=dropout)
        # self.block_bilstm = nn.LSTM(self.block_emb_dim, self.block_rnn_dim,
        #                           num_layers=self.block_rnn_layers, bidirectional=True, dropout=dropout)


        self.crf = CRF(self.block_rnn_dim*2, self.tagset_size)

        self.for_lm_hw = Highway(self.instr_rnn_dim, num_layers=self.highway_layers, dropout=dropout)
        self.back_lm_hw = Highway(self.instr_rnn_dim, num_layers=self.highway_layers, dropout=dropout)
        self.subblock_hw = Highway(self.instr_rnn_dim * 2, num_layers=self.highway_layers, dropout=dropout)

        self.for_lm_out = nn.Linear(self.instr_rnn_dim, self.lm_vocab_size)
        self.back_lm_out = nn.Linear(self.instr_rnn_dim, self.lm_vocab_size)

    def forward(self, imaps_f, imaps_b, imakers_f, imakers_b, bmaps, tmaps, bmap_lengths, imap_lengths):
        self.batch_size = imaps_f.size(0)
        self.block_pad_len = bmaps.size(1)

        imap_lengths, sorted_ind = imap_lengths.sort(dim=0, descending=True)
        imaps_f = imaps_f[sorted_ind]
        imaps_b = imaps_b[sorted_ind]
        imakers_f = imakers_f[sorted_ind]
        imakers_b = imakers_b[sorted_ind]

        instr_f = self.instr_embeds(imaps_f)
        instr_b = self.instr_embeds(imaps_b)

        instr_f = self.dropout(instr_f)
        instr_b = self.dropout(instr_b)

        instr_f = pack_padded_sequence(instr_f, imap_lengths.tolist(), batch_first=True)
        instr_b = pack_padded_sequence(instr_b, imap_lengths.tolist(), batch_first=True)

        instr_f, _ = self.for_instr_lstm(instr_f)
        instr_b, _ = self.back_instr_lstm(instr_b)

        instr_f, _ = pad_packed_sequence(instr_f, batch_first=True)
        instr_b, _ = pad_packed_sequence(instr_b, batch_first=True)

        assert instr_f.size(1) == max(imap_lengths.tolist()) == list(imap_lengths)[0]

        imakers_f = imakers_f.unsqueeze(2).expand(self.batch_size, self.block_pad_len, self.instr_rnn_dim)
        imakers_b = imakers_b.unsqueeze(2).expand(self.batch_size, self.block_pad_len, self.instr_rnn_dim)
        if_selected = torch.gather(instr_f, 1, imakers_f)
        ib_selected = torch.gather(instr_b, 1, imakers_b)

        if self.training:
            # lm_f = self.for_lm_hw(self.dropout(if_selected))
            # lm_b = self.back_lm_hw(self.dropout(ib_selected))
            # lm_f_scores = self.for_lm_out(self.dropout(lm_f))
            # lm_b_scores = self.back_lm_out(self.dropout(lm_b))
            lm_b_scores = self.back_lm_out(self.dropout(ib_selected))
            lm_f_scores = self.for_lm_out(self.dropout(if_selected))

        bmap_lengths, block_sorted_ind = bmap_lengths.sort(dim=0, descending=True)
        bmaps = bmaps[block_sorted_ind]
        tmaps = tmaps[block_sorted_ind]
        if_selected = if_selected[block_sorted_ind]
        ib_selected = ib_selected[block_sorted_ind]
        if self.training:
            lm_f_scores = lm_f_scores[block_sorted_ind]
            lm_b_scores = lm_b_scores[block_sorted_ind]
        # lm_f_scores

        b = self.block_embeds(bmaps)
        b = self.dropout(b)

        # subblock = self.subblock_hw(self.dropout(torch.cat((if_selected, ib_selected), dim=2)))
        # subblock = self.dropout(subblock)

        subblock = self.dropout(torch.cat((if_selected, ib_selected), dim=2))

        b = torch.cat((b, subblock), dim=2)

        b = pack_padded_sequence(b, list(bmap_lengths), batch_first=True)
        b, _ = self.block_bilstm(b)
        b, _ = pad_packed_sequence(b, batch_first=True)
        b = self.dropout(b)
        crf_scores = self.crf(b)

        if self.training:
            return crf_scores, lm_f_scores, lm_b_scores, bmaps, tmaps, bmap_lengths, block_sorted_ind, sorted_ind
            # return crf_scores, bmaps, tmaps, bmap_lengths, block_sorted_ind, sorted_ind
        else:
            return crf_scores, bmaps, tmaps, bmap_lengths, block_sorted_ind, sorted_ind
