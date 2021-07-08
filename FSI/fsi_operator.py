import os
import pickle

import torch
import time
import torch.nn as nn

from sklearn.metrics import f1_score
from torch.nn.utils.rnn import pad_packed_sequence, pack_padded_sequence

from model.FSI_BILSTM_CRF import FSI_BiLSTM_CRF
from utils.viterbi import cal_lstm_crf_loss, decode
from utils import config, common
from utils.dataset import BIDataset
from utils.common import clip_gradient

class FSI_operator():
    def __init__(self, instrset_size, blockset_size, tagset_size):
        self.device = config.device
        self.model = FSI_BiLSTM_CRF(tagset_size=tagset_size,
                                    instrset_size=instrset_size,
                                    instr_emb_dim=config.instr_emb_dim,
                                    instr_rnn_dim=config.instr_rnn_dim,
                                    instr_rnn_layers=config.instr_rnn_layers,
                                    lm_vocab_size=blockset_size,
                                    blokckset_size=blockset_size,
                                    block_emb_dim=config.block_emb_dim,
                                    block_rnn_dim=config.block_rnn_dim,
                                    block_rnn_layers=config.block_rnn_layers,
                                    dropout=config.dropout).to(self.device)
        self.epoches = config.trainning_epoches
        self.print_step = config.print_step
        self.lr = config.lr
        self.lr_decay = config.lr_decay
        self.grad_clip = config.grad_clip
        self.batch_size = config.batch_size
        self.epoches_since_improvement = 0
        self.workers = config.workers

        self.optimizer = torch.optim.SGD(self.model.parameters(), lr=self.lr)

        self.step = 0
        self._bset_f1 = 0.
        self.best_model = None

    def train_step(self, train_loader, block_map, tag_map, epoch):
        self.model.train()
        data_time = common.AverageMeter()
        vb_losses = common.AverageMeter()
        lm_losses = common.AverageMeter()
        f1s = common.AverageMeter()
        batch_time = common.AverageMeter()

        start = time.time()

        lm_criterion = nn.CrossEntropyLoss().to(self.device)

        for i, (bmaps, imaps_f, imaps_b, imakers_f, imakers_b, tmaps, bmap_lengths, imap_lengths, addrs) in enumerate(train_loader):
            data_time.update(time.time()-start)
            max_block_len = max(bmap_lengths.tolist())
            max_instr_len = max(imap_lengths.tolist())

            bmaps = bmaps[:, :max_block_len].to(self.device)
            tmaps = tmaps[:, :max_block_len].to(self.device)
            bmap_lengths = bmap_lengths.to(self.device)

            imaps_f = imaps_f[:, :max_instr_len].to(self.device)
            imaps_b = imaps_b[:, :max_instr_len].to(self.device)
            imakers_f = imakers_f[:, :max_block_len].to(self.device)
            imakers_b = imakers_b[:, :max_block_len].to(self.device)

            crf_scores, lm_f_scores, lm_b_scores, bmaps_sorted, \
                tmaps_sorted, bmap_lengths_sorted, _, _ = self.model(imaps_f,imaps_b, imakers_f, imakers_b, bmaps,
                                                                     tmaps, bmap_lengths, imap_lengths)
            # crf_scores, lm_f_scores, tmaps_sorted, bmap_lengths_sorted, _, _ = self.model(imaps_f,imaps_b, imakers_f, imakers_b, bmaps,
            #                                                      tmaps, bmap_lengths, imap_lengths)

            lm_lengths = bmap_lengths_sorted - 1
            lm_lengths = lm_lengths.tolist()

            lm_f_scores = pack_padded_sequence(lm_f_scores, lm_lengths, batch_first=True)[0]
            lm_b_scores = pack_padded_sequence(lm_b_scores, lm_lengths, batch_first=True)[0]

            lm_f_targets = bmaps_sorted[:, 1:]
            lm_f_targets = pack_padded_sequence(lm_f_targets, lm_lengths, batch_first=True)[0]

            lm_b_targets = torch.cat(
                [torch.LongTensor([block_map['<end>']] * bmaps_sorted.size(0)).unsqueeze(1).to(self.device),
                 bmaps_sorted],
                dim=1)
            lm_b_targets = pack_padded_sequence(lm_b_targets, lm_lengths, batch_first=True)[0]

            lm_loss = lm_criterion(lm_f_scores, lm_f_targets) + lm_criterion(lm_b_scores, lm_b_targets)
            vb_loss = cal_lstm_crf_loss(crf_scores, tmaps_sorted, tag_map, bmap_lengths_sorted)
            loss = vb_loss + lm_loss
            # loss = vb_loss
            lm_losses.update(lm_loss.item(), sum(lm_lengths))
            vb_losses.update(vb_loss.item(), crf_scores.size(0))

            self.optimizer.zero_grad()
            loss.backward()

            if self.grad_clip is not None:
                clip_gradient(self.optimizer, self.grad_clip)

            self.optimizer.step()

            decoded = decode(crf_scores.to(self.device), bmap_lengths_sorted.to(self.device), tag_map)

            decoded = pack_padded_sequence(decoded, (bmap_lengths_sorted - 1).tolist(), batch_first=True)[0]
            tmaps_sorted = tmaps_sorted % len(tag_map)
            tmaps_sorted = pack_padded_sequence(tmaps_sorted, (bmap_lengths_sorted - 1).tolist(), batch_first=True)[0]

            f1 = f1_score(tmaps_sorted.cpu().numpy(), decoded.cpu().numpy(), average='macro')
            batch_time.update(time.time() - start)

            f1s.update(f1, sum((bmap_lengths_sorted - 1).tolist()))

            start = time.time()
            if i % self.print_step == 0:
                print('Epoch: [{0}][{1}/{2}]\t'
                      'Batch Time {batch_time.val:.3f} ({batch_time.avg:.3f})\t'
                      'Data Load Time {data_time.val:.3f} ({data_time.avg:.3f})\t'
                      'CE Loss {ce_loss.val:.4f} ({ce_loss.avg:.4f})\t'
                      'VB Loss {vb_loss.val:.4f} ({vb_loss.avg:.4f})\t'
                      'F1 {f1.val:.3f} ({f1.avg:.3f})'.format(epoch, i, len(train_loader),
                                                              batch_time=batch_time,
                                                              data_time=data_time, ce_loss=lm_losses,
                                                              vb_loss=vb_losses, f1=f1s))

    def train(self, train_block_lists, train_instr_lists, train_tag_lists, val_block_lists, val_instr_lists,
              val_tag_lists, block_map, instr_map, tag_map, train_addrs, val_addrs):
        start_time = time.time()
        train_inputs = common.create_input_tensors_(train_block_lists, train_instr_lists, train_tag_lists, block_map,
                                                    tag_map, train_addrs, instr_map)
        val_inputs = common.create_input_tensors_(val_block_lists, val_instr_lists, val_tag_lists, block_map, tag_map,
                                                 val_addrs, instr_map)

        train_loader = torch.utils.data.DataLoader(BIDataset(*train_inputs), batch_size=self.batch_size,
                                                   num_workers=self.workers, pin_memory=False)
        val_loader = torch.utils.data.DataLoader(BIDataset(*val_inputs), batch_size=self.batch_size,
                                                 num_workers=self.workers, pin_memory=False)
        datas = {}
        for epoch in range(self.step, self.epoches):
            self.train_step(train_loader, block_map, tag_map, epoch)
            val_f1 = validate(self.model, val_loader, tag_map)
            is_best_f1 = val_f1 > self._bset_f1
            self._bset_f1 = max(val_f1, self._bset_f1)
            if not is_best_f1:
                self.epoches_since_improvement += 1
                print("\nEpochs since improvement: %d\n" % (self.epoches_since_improvement,))
            else:
                self.epoches_since_improvement = 0

            epoch_time = time.time()-start_time

            print(epoch_time)
            datas[epoch] = (val_f1, epoch_time)

            common.save_checkpoint(config.modle_output, config.dtype, epoch, self.model, self.optimizer, val_f1,
                                   block_map, instr_map, tag_map, is_best_f1, datas)

            common.adjust_learning_rate(self.optimizer, self.lr / (1 + (epoch + 1) * self.lr_decay))



def validate(model, val_loader, tag_map):
    model.eval()
    batch_time = common.AverageMeter()
    vb_losses = common.AverageMeter()
    f1s = common.AverageMeter()

    start = time.time()

    for i, (bmaps, imaps_f, imaps_b, imakers_f, imakers_b, tmaps, bmap_lengths, imap_lengths, addrs) in enumerate(
            val_loader):
        max_block_len = max(bmap_lengths.tolist())
        max_instr_len = max(imap_lengths.tolist())

        bmaps = bmaps[:, :max_block_len].to(config.device)
        tmaps = tmaps[:, :max_block_len].to(config.device)
        bmap_lengths = bmap_lengths.to(config.device)

        imaps_f = imaps_f[:, :max_instr_len].to(config.device)
        imaps_b = imaps_b[:, :max_instr_len].to(config.device)
        imakers_f = imakers_f[:, :max_block_len].to(config.device)
        imakers_b = imakers_b[:, :max_block_len].to(config.device)

        crf_scores, bmaps_sorted, tmaps_sorted, bmap_lengths_sorted, _, _ = \
            model(imaps_f, imaps_b, imakers_f, imakers_b, bmaps, tmaps, bmap_lengths, imap_lengths)

        vb_loss = cal_lstm_crf_loss(crf_scores, tmaps_sorted, tag_map, bmap_lengths_sorted)
        vb_losses.update(vb_loss.item(), crf_scores.size(0))

        decoded = decode(crf_scores.to(config.device), bmap_lengths_sorted.to(config.device), tag_map)

        decoded = pack_padded_sequence(decoded, (bmap_lengths_sorted - 1).tolist(), batch_first=True)[0]
        tmaps_sorted = tmaps_sorted % len(tag_map)
        tmaps_sorted = pack_padded_sequence(tmaps_sorted, (bmap_lengths_sorted - 1).tolist(), batch_first=True)[0]

        f1 = f1_score(tmaps_sorted.cpu().numpy(), decoded.cpu().numpy(), average='macro')
        batch_time.update(time.time() - start)

        f1s.update(f1, sum((bmap_lengths_sorted - 1).tolist()))
        start = time.time()

        if i % config.print_step == 0:
            print('Validation: [{0}/{1}]\t'
                  'Batch Time {batch_time.val:.3f} ({batch_time.avg:.3f})\t'
                  'VB Loss {vb_loss.val:.4f} ({vb_loss.avg:.4f})\t'
                  'F1 Score {f1.val:.3f} ({f1.avg:.3f})\t'.format(i, len(val_loader), batch_time=batch_time,
                                                                  vb_loss=vb_losses, f1=f1s))

    print('\n * LOSS - {vb_loss.avg:.3f}, F1 SCORE - {f1.avg:.3f}\n'.format(vb_loss=vb_losses,
                                                                            f1=f1s))
    return f1s.avg


def test(model, test_block_lists, test_instr_lists, test_tag_lists, addresses, block_map, instr_map, tag_map):
    model.eval()
    #blocks, blocks_instr, tags, block_map, tag_map, addresses, instr_map
    test_inputs = common.create_input_tensors_(test_block_lists, test_instr_lists, test_tag_lists, block_map, tag_map,
                                               addresses, instr_map)

    test_loader = torch.utils.data.DataLoader(BIDataset(*test_inputs), batch_size=config.batch_size, shuffle=True,
                                              num_workers=config.workers, pin_memory=False)
    pred_tag_lists = []
    gloden_tag_lists = []
    all_addrs = []
    for k, (bmaps, imaps_f, imaps_b, imakers_f, imakers_b, tmaps, bmap_lengths, imap_lengths, addrs) in enumerate(
            test_loader):
        start_time = time.time()
        max_block_len = max(bmap_lengths.tolist())
        max_instr_len = max(imap_lengths.tolist())

        bmaps = bmaps[:, :max_block_len].to(config.device)
        tmaps = tmaps[:, :max_block_len].to(config.device)
        bmap_lengths = bmap_lengths.to(config.device)

        imaps_f = imaps_f[:, :max_instr_len].to(config.device)
        imaps_b = imaps_b[:, :max_instr_len].to(config.device)
        imakers_f = imakers_f[:, :max_block_len].to(config.device)
        imakers_b = imakers_b[:, :max_block_len].to(config.device)

        crf_scores, bmaps_sorted, tmaps_sorted, bmap_lengths_sorted, _, _ = \
            model(imaps_f, imaps_b, imakers_f, imakers_b, bmaps, tmaps, bmap_lengths, imap_lengths)
        decoded = decode(crf_scores.to(config.device), bmap_lengths_sorted.to(config.device), tag_map)
        tmaps_sorted = tmaps_sorted % len(tag_map)

        tmaps_sorted = tmaps_sorted.to("cpu").numpy().tolist()
        decoded = decoded.to("cpu").numpy().tolist()
        decoded_time = time.time() - start_time

        _, block_sort_ind = bmap_lengths.sort(dim=0, descending=True)
        _addrs = []
        for ind in block_sort_ind:
            all_addrs.append(addrs[ind])
            _addrs.append(addrs[ind])

        with open(os.path.join(config.fsi_result_path, str(k)), "wb+") as f:
            pickle.dump((_addrs, crf_scores, bmap_lengths_sorted, decoded_time, tag_map), f)

        for i, bmap_length in enumerate(bmap_lengths_sorted):
            gloden_tag_list = tmaps_sorted[i][:bmap_length-1]
            pred_tag_list = decoded[i][:bmap_length-1]
            gloden_tag_lists.append(gloden_tag_list)
            pred_tag_lists.append(pred_tag_list)

        if k % config.print_step == 0:
            print("completed {0}/{1}".format(k, len(test_loader)))

    _gloden_tag_lists = []
    _pred_tag_lists = []
    id2tag = dict((id_, tag) for tag, id_ in tag_map.items())
    for gloden_tag_list, pred_tag_list in zip(gloden_tag_lists, pred_tag_lists):
        assert len(gloden_tag_list) == len(pred_tag_list)

        _gloden_tag_list = []
        for tag_id in gloden_tag_list:
            _gloden_tag_list.append(id2tag[tag_id])
        _gloden_tag_lists.append(_gloden_tag_list)

        _pred_tag_list = []
        for i in range(len(pred_tag_list)):
            _pred_tag_list.append(id2tag[pred_tag_list[i]])
        _pred_tag_lists.append(_pred_tag_list)

    return _pred_tag_lists, _gloden_tag_lists, all_addrs
